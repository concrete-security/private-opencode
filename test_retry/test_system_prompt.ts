/**
 * Test that systemPrompt config overrides the default pattern-matching.
 *
 * The model "openai/gpt-oss-120b" contains "gpt-" so by default it gets PROMPT_BEAST.
 * With systemPrompt: "anthropic", it should get PROMPT_ANTHROPIC instead.
 */
import { SystemPrompt } from "../packages/opencode/src/session/system"
import type { Provider } from "../packages/opencode/src/provider/provider"

const ANTHROPIC_MARKER = "You are OpenCode, the best coding agent on the planet"
const BEAST_MARKER = "You are opencode, an agent - please keep going until"

// Helper to create a minimal model object
function makeModel(apiId: string, systemPrompt?: any): Provider.Model {
  return {
    id: "test",
    providerID: "test-provider",
    api: { id: apiId, url: "http://localhost", npm: "@ai-sdk/openai-compatible" },
    name: "test-model",
    capabilities: {
      temperature: false,
      reasoning: false,
      attachment: false,
      toolcall: true,
      input: { text: true, audio: false, image: false, video: false, pdf: false },
      output: { text: true, audio: false, image: false, video: false, pdf: false },
      interleaved: false,
    },
    cost: { input: 0, output: 0, cache: { read: 0, write: 0 } },
    limit: { context: 128000, output: 4096 },
    status: "active",
    options: {},
    headers: {},
    release_date: "2025-01-01",
    systemPrompt,
  } as Provider.Model
}

// Test 1: gpt- model without systemPrompt → should get BEAST
const model1 = makeModel("openai/gpt-oss-120b")
const result1 = SystemPrompt.provider(model1)
const text1 = result1.join("\n")
console.log("Test 1: gpt- model WITHOUT systemPrompt override")
console.log(`  Contains BEAST marker: ${text1.includes(BEAST_MARKER)}`)
console.log(`  Contains ANTHROPIC marker: ${text1.includes(ANTHROPIC_MARKER)}`)
console.assert(text1.includes(BEAST_MARKER), "FAIL: expected BEAST prompt for gpt- model")
console.assert(!text1.includes(ANTHROPIC_MARKER), "FAIL: should NOT contain ANTHROPIC prompt")
console.log("  PASS ✓\n")

// Test 2: gpt- model WITH systemPrompt: "anthropic" → should get ANTHROPIC
const model2 = makeModel("openai/gpt-oss-120b", "anthropic")
const result2 = SystemPrompt.provider(model2)
const text2 = result2.join("\n")
console.log("Test 2: gpt- model WITH systemPrompt: 'anthropic'")
console.log(`  Contains BEAST marker: ${text2.includes(BEAST_MARKER)}`)
console.log(`  Contains ANTHROPIC marker: ${text2.includes(ANTHROPIC_MARKER)}`)
console.assert(!text2.includes(BEAST_MARKER), "FAIL: should NOT contain BEAST prompt")
console.assert(text2.includes(ANTHROPIC_MARKER), "FAIL: expected ANTHROPIC prompt")
console.log("  PASS ✓\n")

// Test 3: claude model without override → should get ANTHROPIC (default)
const model3 = makeModel("claude-3-opus")
const result3 = SystemPrompt.provider(model3)
const text3 = result3.join("\n")
console.log("Test 3: claude model WITHOUT override (default behavior)")
console.log(`  Contains ANTHROPIC marker: ${text3.includes(ANTHROPIC_MARKER)}`)
console.assert(text3.includes(ANTHROPIC_MARKER), "FAIL: expected ANTHROPIC for claude")
console.log("  PASS ✓\n")

// Test 4: claude model WITH systemPrompt: "beast" → should get BEAST
const model4 = makeModel("claude-3-opus", "beast")
const result4 = SystemPrompt.provider(model4)
const text4 = result4.join("\n")
console.log("Test 4: claude model WITH systemPrompt: 'beast'")
console.log(`  Contains BEAST marker: ${text4.includes(BEAST_MARKER)}`)
console.log(`  Contains ANTHROPIC marker: ${text4.includes(ANTHROPIC_MARKER)}`)
console.assert(text4.includes(BEAST_MARKER), "FAIL: expected BEAST prompt")
console.assert(!text4.includes(ANTHROPIC_MARKER), "FAIL: should NOT contain ANTHROPIC")
console.log("  PASS ✓\n")

console.log("All tests passed!")
