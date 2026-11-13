package app.authenticator

import android.content.ContentResolver
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.ImageDecoder
import android.net.Uri
import android.os.Build
import androidx.camera.core.ImageProxy
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.multi.qrcode.QRCodeMultiReader
import com.google.zxing.qrcode.QRCodeReader
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/** QR decoding (camera frames, screenshots) and encoding (export). Fully offline (ZXing). */
object QrCodes {
    private val hints = mapOf(
        DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
        DecodeHintType.TRY_HARDER to true,
    )

    /** Largest image side we decode; bigger photos are scaled down first. */
    private const val MAX_SIDE = 2400

    /** Decodes the luminance (Y) plane of a camera frame. Call from the analyzer thread. */
    fun decodeFrame(image: ImageProxy, reader: QRCodeReader): String? {
        val plane = image.planes[0]
        val buffer = plane.buffer
        val data = ByteArray(buffer.remaining())
        buffer.get(data)
        val rowStride = plane.rowStride
        val rows = if (rowStride > 0) (data.size + rowStride - 1) / rowStride else return null
        if (rows < image.height) return null
        val source = PlanarYUVLuminanceSource(data, rowStride, image.height, 0, 0, image.width, image.height, false)
        return try {
            reader.decode(BinaryBitmap(HybridBinarizer(source)), hints).text
        } catch (e: ReaderException) {
            null
        } finally {
            reader.reset()
        }
    }

    fun decodeImage(resolver: ContentResolver, uri: Uri): List<String> {
        val bitmap = loadBitmap(resolver, uri) ?: throw IllegalArgumentException("Could not open the image")
        return try {
            decodeBitmap(bitmap)
        } finally {
            bitmap.recycle()
        }
    }

    private fun loadBitmap(resolver: ContentResolver, uri: Uri): Bitmap? =
        if (Build.VERSION.SDK_INT >= 28) {
            ImageDecoder.decodeBitmap(ImageDecoder.createSource(resolver, uri)) { decoder, info, _ ->
                decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
                val side = maxOf(info.size.width, info.size.height)
                if (side > MAX_SIDE) {
                    val scale = MAX_SIDE.toDouble() / side
                    decoder.setTargetSize((info.size.width * scale).toInt(), (info.size.height * scale).toInt())
                }
            }
        } else {
            val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            resolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, bounds) }
            var sample = 1
            while (maxOf(bounds.outWidth, bounds.outHeight) / sample > MAX_SIDE) sample *= 2
            resolver.openInputStream(uri)?.use {
                BitmapFactory.decodeStream(it, null, BitmapFactory.Options().apply { inSampleSize = sample })
            }
        }

    fun decodeBitmap(bitmap: Bitmap): List<String> {
        val w = bitmap.width
        val h = bitmap.height
        val pixels = IntArray(w * h)
        bitmap.getPixels(pixels, 0, w, 0, 0, w, h)
        // Transparent pixels become white, like a screenshot background.
        for (i in pixels.indices) {
            val p = pixels[i]
            val a = p ushr 24
            if (a < 255) {
                fun blend(c: Int) = (c * a + 255 * (255 - a)) / 255
                pixels[i] = (0xff shl 24) or (blend((p shr 16) and 0xff) shl 16) or
                    (blend((p shr 8) and 0xff) shl 8) or blend(p and 0xff)
            }
        }
        val source = RGBLuminanceSource(w, h, pixels)
        return decodeSource(source).ifEmpty { decodeSource(source.invert()) }
    }

    private fun decodeSource(source: LuminanceSource): List<String> {
        val bitmap = BinaryBitmap(HybridBinarizer(source))
        return try {
            QRCodeMultiReader().decodeMultiple(bitmap, hints).map { it.text }.distinct()
        } catch (e: NotFoundException) {
            try {
                listOf(QRCodeReader().decode(bitmap, hints).text)
            } catch (e: ReaderException) {
                emptyList()
            }
        } catch (e: ReaderException) {
            emptyList()
        }
    }

    /** One pixel per module (plus the quiet zone); draw scaled without filtering. */
    fun encode(text: String): Bitmap {
        val matrix = QRCodeWriter().encode(
            text,
            BarcodeFormat.QR_CODE,
            0,
            0,
            mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.MARGIN to 4),
        )
        val w = matrix.width
        val h = matrix.height
        val pixels = IntArray(w * h) { i -> if (matrix.get(i % w, i / w)) 0xff000000.toInt() else 0xffffffff.toInt() }
        return Bitmap.createBitmap(pixels, w, h, Bitmap.Config.ARGB_8888)
    }
}
