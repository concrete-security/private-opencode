/**
 * Tests for the security indicator displayed in the session header.
 *
 * The "concrete-security" provider uses an encrypted channel, so the UI
 * shows a visual cue reflecting whether the exchange succeeded (secure)
 * or failed (unsecure). Other providers should produce no indicator.
 */
import { describe, expect, test } from "bun:test"
import { getSecurityIndicator } from "../../../src/cli/cmd/tui/util/provider"

describe("getSecurityIndicator", () => {
  // When the provider is "concrete-security" and no error occurred,
  // the channel is considered secure.
  test("concrete-security without error returns secure", () => {
    const result = getSecurityIndicator("concrete-security", false)
    expect(result).toEqual({ label: "🔐 Secure ", status: "secure" })
  })

  // When the provider is "concrete-security" but an error occurred,
  // the channel is flagged as unsecure.
  test("concrete-security with error returns unsecure", () => {
    const result = getSecurityIndicator("concrete-security", true)
    expect(result).toEqual({ label: "⚠ Unsecure ", status: "error" })
  })

  // Non-regression: any other provider should produce no indicator at all.
  test("other provider returns empty label", () => {
    const result = getSecurityIndicator("anthropic", false)
    expect(result).toEqual({ label: "", status: "none" })
  })
})
