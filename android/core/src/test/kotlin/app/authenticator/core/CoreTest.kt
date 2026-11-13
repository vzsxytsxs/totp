package app.authenticator.core

import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Shared vectors in docs/test-vectors, also checked by the Windows test suite. */
class VectorsTest {
    private val dir = File(System.getProperty("vectors.dir") ?: "../../docs/test-vectors")
    private val vectors = JSONObject(File(dir, "vectors.json").readText())

    private fun account(json: JSONObject) = Account.fromJson(json)

    @Test
    fun totpAndHotp() {
        val totp = vectors.getJSONArray("totp")
        for (i in 0 until totp.length()) {
            val c = totp.getJSONObject(i)
            val a = Account(
                secret = Base32.decode(c.getString("secret")),
                algorithm = HashAlgorithm.parse(c.getString("algorithm"))!!,
                digits = c.getInt("digits"),
                period = c.getInt("period"),
            )
            assertEquals(c.getString("code"), a.codeAt(c.getLong("time")), c.toString())
        }
        val hotp = vectors.getJSONArray("hotp")
        for (i in 0 until hotp.length()) {
            val c = hotp.getJSONObject(i)
            val a = Account(type = OtpType.HOTP, secret = Base32.decode(c.getString("secret")), counter = c.getLong("counter"))
            assertEquals(c.getString("code"), a.codeAt(0), c.toString())
        }
    }

    @Test
    fun otpauthUris() {
        val cases = vectors.getJSONArray("otpauth")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            assertEquals(account(c.getJSONObject("account")), OtpAuth.parse(c.getString("uri")), c.getString("uri"))
        }
        val invalid = vectors.getJSONArray("otpauth_invalid")
        for (i in 0 until invalid.length()) {
            assertFailsWith<OtpException>(invalid.getString(i)) { OtpAuth.parse(invalid.getString(i)) }
        }
    }

    @Test
    fun googleMigration() {
        val m = vectors.getJSONObject("migration")
        val batch = Migration.decodeUri(m.getString("uri"))
        val expected = m.getJSONArray("accounts")
        assertEquals((0 until expected.length()).map { account(expected.getJSONObject(it)) }, batch.accounts)
    }

    @Test
    fun backupsFromBothPlatforms() {
        val backups = vectors.getJSONArray("backups")
        for (i in 0 until backups.length()) {
            val c = backups.getJSONObject(i)
            val bytes = File(dir, c.getString("file")).readBytes()
            val restored = Backup.open(bytes, c.getString("password"))
            val expected = c.getJSONArray("accounts")
            assertEquals((0 until expected.length()).map { account(expected.getJSONObject(it)) }, restored.accounts)
            assertEquals(0, restored.invalidEntries)
            val e = assertFailsWith<Backup.BackupException> { Backup.open(bytes, "wrong password") }
            assertEquals(Backup.Failure.WRONG_PASSWORD, e.failure)
        }
    }

    /** Regenerates the fixture the Windows tests decrypt: WRITE_FIXTURES=1 gradle test */
    @Test
    fun writeAndroidFixture() {
        if (System.getenv("WRITE_FIXTURES") != "1") return
        val accounts = listOf(
            OtpAuth.parse("otpauth://totp/Microsoft:maria@outlook.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&issuer=Microsoft"),
            OtpAuth.parse("otpauth://totp/Exchange:conta%20%C3%BAnica?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512&digits=8"),
            OtpAuth.parse("otpauth://hotp/Token?secret=GEZDGNBVGY3TQOJQ&counter=42"),
        )
        val file = Backup.create(accounts, "senha do backup: açaí 123", Backup.KdfParams(8 * 1024, 1, 1))
        File(dir, "backup-from-android.json").writeText(file + "\n")
    }
}

class CoreTest {
    private fun sample(i: Int, type: OtpType = OtpType.TOTP) = Account(
        type = type,
        issuer = "Issuer $i",
        name = "user$i@example.com",
        secret = ByteArray(20) { (it * 7 + i).toByte() },
        algorithm = if (i % 3 == 0) HashAlgorithm.SHA256 else HashAlgorithm.SHA1,
        digits = if (i % 2 == 0) 8 else 6,
        counter = if (type == OtpType.HOTP) i.toLong() else 0,
    )

    @Test
    fun base32() {
        assertEquals("MZXW6YTBOI", Base32.encode("foobar".toByteArray()))
        assertContentEquals("foobar".toByteArray(), Base32.decode("mzxw 6ytb-oi======"))
        assertFailsWith<OtpException> { Base32.decode("MZXW1") }
        assertFailsWith<OtpException> { Base32.decode("  ") }
    }

    @Test
    fun migrationRoundTripAcrossBatches() {
        val accounts = (0 until 40).map { sample(it, if (it % 5 == 0) OtpType.HOTP else OtpType.TOTP) }
        val uris = Migration.encodeUris(accounts, 4242)
        assertTrue(uris.size > 1)
        val decoded = uris.flatMapIndexed { i, uri ->
            assertTrue(uri.length < 1000)
            val batch = Migration.decodeUri(uri)
            assertEquals(i, batch.info.index)
            assertEquals(uris.size, batch.info.size)
            assertEquals(4242, batch.info.id)
            batch.accounts
        }
        assertEquals(accounts, decoded)
    }

    @Test
    fun migrationRejectsGarbage() {
        assertFailsWith<OtpException> { Migration.decodeUri("otpauth-migration://offline?data=%%%") }
        assertFailsWith<OtpException> { Migration.decodeUri("otpauth-migration://offline?data=CgQKAg") }
    }

    @Test
    fun backupRoundTrip() {
        val fast = Backup.KdfParams(8 * 1024, 1, 1)
        val accounts = listOf(sample(1), sample(2, OtpType.HOTP))
        val file = Backup.create(accounts, "correct horse çá", fast)
        assertTrue(!file.contains(Base32.encode(accounts[0].secret)))
        assertEquals(accounts, Backup.open(file.toByteArray(), "correct horse çá").accounts)
        // Same password typed in decomposed Unicode form.
        assertEquals(accounts, Backup.open(file.toByteArray(), "correct horse çá").accounts)
        val hostile = file.replace("\"memory_kib\": 8192", "\"memory_kib\": 2000000000")
        assertEquals(
            Backup.Failure.UNSUPPORTED,
            assertFailsWith<Backup.BackupException> { Backup.open(hostile.toByteArray(), "x") }.failure,
        )
        assertEquals(
            Backup.Failure.WRONG_FORMAT,
            assertFailsWith<Backup.BackupException> { Backup.open("{}".toByteArray(), "x") }.failure,
        )
    }

    @Test
    fun importParser() {
        val result = ImportParser.parse("otpauth://totp/A:b?secret=JBSWY3DPEHPK3PXP")
        assertEquals("A", result.accounts.single().issuer)
        assertFailsWith<OtpException> { ImportParser.parse("hello") }
    }
}
