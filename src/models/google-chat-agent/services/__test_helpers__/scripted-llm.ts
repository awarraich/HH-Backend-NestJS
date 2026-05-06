import type OpenAI from 'openai';
import type {
  ChatCompletion,
  ChatCompletionMessageParam,
} from 'openai/resources/chat/completions';

/**
 * Test helper: a fake OpenAI client whose `chat.completions.create`
 * returns scripted responses in order. Use it to exercise multi-turn
 * tool-use loops and full agent-pipeline scenarios deterministically.
 *
 * Each scripted response can be either:
 *   - a tool-call response (the model wants to call one or more tools), or
 *   - a final text response (the model is done).
 *
 * The helper records every `messages` array sent to the API, so tests can
 * assert that prior turns and tool results were threaded correctly.
 */
export interface ScriptedOpenAI extends Pick<OpenAI, 'chat'> {
  __calls: Array<{ messages: ChatCompletionMessageParam[]; tools?: unknown }>;
}

export function scriptedOpenAI(responses: ChatCompletion[]): ScriptedOpenAI {
  let i = 0;
  const calls: ScriptedOpenAI['__calls'] = [];
  const create = jest.fn(async (args: unknown) => {
    const a = args as {
      messages: ChatCompletionMessageParam[];
      tools?: unknown;
    };
    // Deep-clone the messages array — the loop reuses + mutates a single
    // array across iterations, so a reference snapshot would show the
    // post-loop state on every call.
    const messagesSnapshot = JSON.parse(
      JSON.stringify(a.messages),
    ) as ChatCompletionMessageParam[];
    calls.push({ messages: messagesSnapshot, tools: a.tools });
    if (i >= responses.length) {
      throw new Error(
        `scriptedOpenAI: ran out of scripted responses on call ${i + 1}`,
      );
    }
    return responses[i++];
  });
  return {
    chat: { completions: { create } } as unknown as OpenAI['chat'],
    __calls: calls,
  };
}

/** Build a tool-call response from an array of {name, arguments} pairs. */
export function toolCallResponse(
  toolCalls: Array<{ id?: string; name: string; argsJson: string }>,
  usage: { promptTokens: number; completionTokens: number } = {
    promptTokens: 50,
    completionTokens: 10,
  },
): ChatCompletion {
  return {
    id: `chatcmpl-${Math.random()}`,
    object: 'chat.completion',
    created: Date.now(),
    model: 'gpt-4o',
    choices: [
      {
        index: 0,
        message: {
          role: 'assistant',
          content: null,
          refusal: null,
          tool_calls: toolCalls.map((tc, idx) => ({
            id: tc.id ?? `call_${idx + 1}`,
            type: 'function',
            function: { name: tc.name, arguments: tc.argsJson },
          })),
        },
        logprobs: null,
        finish_reason: 'tool_calls',
      },
    ],
    usage: {
      prompt_tokens: usage.promptTokens,
      completion_tokens: usage.completionTokens,
      total_tokens: usage.promptTokens + usage.completionTokens,
    },
  } as ChatCompletion;
}

/** Build a final text response. */
export function textResponse(
  text: string,
  usage: { promptTokens: number; completionTokens: number } = {
    promptTokens: 50,
    completionTokens: 10,
  },
): ChatCompletion {
  return {
    id: `chatcmpl-${Math.random()}`,
    object: 'chat.completion',
    created: Date.now(),
    model: 'gpt-4o',
    choices: [
      {
        index: 0,
        message: {
          role: 'assistant',
          content: text,
          refusal: null,
        },
        logprobs: null,
        finish_reason: 'stop',
      },
    ],
    usage: {
      prompt_tokens: usage.promptTokens,
      completion_tokens: usage.completionTokens,
      total_tokens: usage.promptTokens + usage.completionTokens,
    },
  } as ChatCompletion;
}
