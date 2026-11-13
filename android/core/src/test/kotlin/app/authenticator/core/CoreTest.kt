package app.authenticator.core

import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
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
            val logins = c.optJSONArray("logins")
            val expectedLogins = if (logins == null) emptyList() else (0 until logins.length()).map { Login.fromJson(logins.getJSONObject(it)) }
            assertEquals(expectedLogins, restored.logins, c.getString("file"))
            assertEquals(0, restored.invalidEntries)
            val e = assertFailsWith<Backup.BackupException> { Backup.open(bytes, "wrong password") }
            assertEquals(Backup.Failure.WRONG_PASSWORD, e.failure)
        }
    }

    /**
     * Regenerates `backup-v2-from-android.json`, which the Windows tests decrypt:
     * WRITE_FIXTURES=1 ./gradlew -p core test. (`backup-from-android.json` was
     * written by version 1.0 and is kept as is.)
     */
    @Test
    fun writeAndroidFixture() {
        if (System.getenv("WRITE_FIXTURES") != "1") return
        val accountId = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        val accounts = listOf(
            OtpAuth.parse("otpauth://totp/Microsoft:maria@outlook.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&issuer=Microsoft")
                .copy(id = accountId),
        )
        val logins = listOf(
            Login("33333333333333333333333333333333", "Outlook", "maria@outlook.com", "Sênha#Forte!2025 ✓",
                "https://login.live.com", "", accountId, 1_710_000_000, 1_710_000_000),
            Login("44444444444444444444444444444444", "Roteador", "admin", "", "http://192.168.0.1",
                "Wi-Fi: casa", "", 1_710_000_000, 1_710_003_600),
        )
        val file = Backup.create(accounts, "backup do celular 2.0 ✓", Backup.KdfParams(8 * 1024, 1, 1), logins)
        File(dir, "backup-v2-from-android.json").writeText(file + "\n")
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

    @Test
    fun otpauthFormatRoundTrip() {
        for (uri in listOf(
            "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
            "otpauth://totp/Banco%20%C3%81gil:jo%C3%A3o%3Ax?secret=GEZDGNBVGY3TQOJQ&algorithm=SHA256&digits=8&period=60",
            "otpauth://hotp/Legacy?secret=GEZDGNBVGY3TQOJQ&counter=3",
            "otpauth://totp/Only%20Issuer:?secret=GEZDGNBVGY3TQOJQ&issuer=Only%20Issuer",
        )) {
            val a = OtpAuth.parse(uri)
            assertEquals(a, OtpAuth.parse(a.toOtpAuth()), uri)
        }
        // Same text as the Windows app produces.
        assertEquals(
            "otpauth://totp/Banco%20%C3%81gil:jo%C3%A3o?secret=GEZDGNBVGY3TQOJQ&issuer=Banco%20%C3%81gil&algorithm=SHA256&digits=8&period=60",
            OtpAuth.parse("otpauth://totp/Banco%20%C3%81gil:jo%C3%A3o?secret=GEZDGNBVGY3TQOJQ&algorithm=SHA256&digits=8&period=60").toOtpAuth(),
        )
    }

    @Test
    fun loginsAndSites() {
        assertEquals(Site("https", "accounts.example.com", 8443), Site.parse("HTTPS://u:p@Accounts.Example.COM.:8443/x?y#z"))
        assertEquals(Site("", "github.com", null), Site.parse("github.com/login"))
        assertEquals(Site("http", "[::1]", 8080), Site.parse("http://[::1]:8080/"))
        assertNull(Site.parse("https://"))
        assertNull(Site.parse("https://exa mple.com"))
        assertEquals("github.com", Login(url = "https://www.github.com/login").displayTitle)
        assertNull(Login(url = "x.com").validationError())
        assertNotNull(Login().validationError())
        val json = Login(id = "1", title = "T", password = "p").toJson()
        assertFalse(json.has("otp"))
        assertEquals(Login(id = "1", title = "T", password = "p"), Login.fromJson(json))
    }

    @Test
    fun mergeRules() {
        val a1 = OtpAuth.parse("otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP").copy(id = "a1")
        val existingLogin = Login("l1", url = "github.com", username = "me", password = "old", otp = "a1", created = 1, modified = 100)
        val merged = Merge.merge(
            listOf(a1),
            listOf(existingLogin),
            listOf(
                a1.copy(id = "phone-a1"),
                OtpAuth.parse("otpauth://totp/Google:me?secret=GEZDGNBVGY3TQOJQ").copy(id = "phone-a2"),
            ),
            listOf(
                Login("l1", url = "github.com", username = "me", password = "new", otp = "phone-a1", created = 1, modified = 200),
                Login("l2", url = "google.com", username = "me", password = "pw", otp = "phone-a2", created = 1, modified = 50),
                Login("", url = "github.com", username = "me", password = "new"),
                Login("l3", url = "example.com", username = "x", password = "y", otp = "missing", created = 1, modified = 10),
            ),
        )
        assertEquals(Merge.Report(1, 1, 2, 1, 1), merged.report)
        assertEquals(listOf("a1", "phone-a2"), merged.accounts.map { it.id })
        assertEquals(listOf("new", "pw", "y"), merged.logins.map { it.password })
        assertEquals(listOf("a1", "phone-a2", ""), merged.logins.map { it.otp })
        assertEquals("1 account and 2 passwords added, 1 password updated, 2 already here.", merged.report.summary())

        val hotp = OtpAuth.parse("otpauth://hotp/T?secret=GEZDGNBVGY3TQOJQ&counter=5").copy(id = "h")
        val bumped = Merge.merge(listOf(hotp), emptyList(), listOf(hotp.copy(id = "", counter = 9)), emptyList())
        assertEquals(9, bumped.accounts.single().counter)

        val fixed = Merge.ensureIds(
            listOf(a1.copy(id = ""), a1.copy(id = "")),
            listOf(Login(url = "a.com", otp = "nope")),
            now = 42,
        )
        assertTrue(fixed.changed)
        assertEquals(2, fixed.accounts.map { it.id }.toSet().size)
        assertEquals("", fixed.logins.single().otp)
        assertEquals(42L, fixed.logins.single().created)
        assertFalse(Merge.ensureIds(fixed.accounts, fixed.logins).changed)
    }

    @Test
    fun passwordGenerator() {
        repeat(200) {
            val p = PasswordGenerator.generate()
            assertEquals(20, p.length)
            assertTrue(p.any { it.isLowerCase() } && p.any { it.isUpperCase() } && p.any { it.isDigit() } && p.any { !it.isLetterOrDigit() })
        }
        val digits = PasswordGenerator.generate(GeneratorOptions(length = 6, lowercase = false, uppercase = false, symbols = false))
        assertTrue(digits.all { it.isDigit() })
        assertEquals(PasswordGenerator.MIN_LENGTH, PasswordGenerator.generate(GeneratorOptions(length = 1)).length)
        assertTrue(PasswordGenerator.generate(GeneratorOptions(length = 128, avoidSimilar = true)).none { it in "Il1O0o" })
    }
}
