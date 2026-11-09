package com.umeagleeye.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.time.LocalDate
import java.util.Base64

class RulesTest {
    private fun b64(json: String) = Base64.getUrlEncoder().withoutPadding().encodeToString(json.toByteArray())

    @Test
    fun connectionCodes() {
        val agent = Codes.parse("  EE1." + b64("""{"u":"https://api.example.com/api/v1/","i":"9845B1E9-FABB-4E94-BA71-98153A4022BA","k":"key123"}""") + "\n")
        assertEquals(Code.Agent("https://api.example.com/api/v1", "9845b1e9-fabb-4e94-ba71-98153a4022ba", "key123"), agent)
        val install = Codes.parse("EE2." + b64("""{"u":"https://api.example.com/api/v1","t":"${"a".repeat(64)}"}"""))
        assertEquals(Code.Install("https://api.example.com/api/v1", "a".repeat(64)), install)
        for (bad in listOf("", "hello", "EE1.%%%", "EE1." + b64("""{"u":"ftp://x","i":"x","k":"y"}"""), "EE2." + b64("""{"u":"https://x","t":"short"}"""))) {
            try {
                Codes.parse(bad)
                fail("accepted: $bad")
            } catch (e: CodeError) {
                assertTrue(e.message!!.isNotBlank())
            }
        }
    }

    @Test
    fun patchAge() {
        val today = LocalDate.of(2026, 11, 9)
        assertEquals(39L, Rules.patchAgeDays("2026-10-01", today))
        assertEquals(0L, Rules.patchAgeDays("2026-12-01", today))       // a date ahead of the clock is not negative
        assertNull(Rules.patchAgeDays("", today))
        assertNull(Rules.patchAgeDays("unknown", today))
    }

    @Test
    fun rootSignals() {
        assertTrue(Rules.rootSignals("release-keys", { false }, { false }).isEmpty())
        assertEquals(listOf("test-keys build", "su binary (/system/xbin/su)", "root app (com.topjohnwu.magisk)"),
            Rules.rootSignals("test-keys", { it == "/system/xbin/su" }, { it == "com.topjohnwu.magisk" }))
    }

    @Test
    fun installIdAndForm() {
        val id = Rules.osInstallId("9774d56d682e549c")!!
        assertEquals(32, id.length)
        assertTrue(id.matches(Regex("^[0-9a-f]{32}$")))
        assertEquals(id, Rules.osInstallId(" 9774D56D682E549C "))
        assertNull(Rules.osInstallId(null))
        assertEquals("phone", Rules.formFactor(411))
        assertEquals("tablet", Rules.formFactor(800))
    }

    @Test
    fun inventoryDue() {
        val hour = 3_600_000L
        assertTrue(Rules.inventoryDue(true, 0, 21600, 10 * hour, false))           // never sent
        assertFalse(Rules.inventoryDue(true, 9 * hour, 21600, 10 * hour, false))   // sent an hour ago
        assertTrue(Rules.inventoryDue(true, 9 * hour, 21600, 10 * hour, true))     // a job asks
        assertFalse(Rules.inventoryDue(false, 0, 21600, 10 * hour, true))          // switched off
        assertTrue(Rules.inventoryDue(true, 3 * hour, 21600, 10 * hour, false))
    }
}
