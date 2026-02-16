/**
 * Returns a security indicator label and status for the given provider.
 *
 * When the provider is "concrete-security", the channel is expected to be
 * encrypted end-to-end. If an error occurred during the exchange the
 * indicator signals an unsecure state; otherwise it confirms the channel
 * is secure. For any other provider, no indicator is shown.
 */
export function getSecurityIndicator(providerID: string, hasError: boolean) {
  if (providerID === "concrete-security") {
    return hasError
      ? { label: "⚠ Unsecure ", status: "error" as const }
      : { label: "🔐 Secure ", status: "secure" as const }
  }
  return { label: "", status: "none" as const }
}
