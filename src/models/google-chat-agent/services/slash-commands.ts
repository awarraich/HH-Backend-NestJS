import type { ResolvedAgentUser } from './agent-identity.types';
import type { AgentReply } from '../types/chat-event.types';

export type SlashCommand = '/help' | '/reset' | '/whoami';

export function isSlashCommand(text: string): text is SlashCommand {
  const trimmed = text.trim().toLowerCase();
  return trimmed === '/help' || trimmed === '/reset' || trimmed === '/whoami';
}

export function buildHelpReply(): AgentReply {
  return {
    text: [
      "*Scheduling assistant — what I can do*",
      '',
      "• *What are my shifts?* I'll list your assigned shifts (default: this week).",
      '• *Tell me about shift X* — details of a shift you\'re assigned to.',
      "• *What shifts are open?* — open shifts in your org that match your role.",
      '',
      "I *cannot* assign or unassign shifts — that's your manager's call. Talk to them about scheduling changes.",
      '',
      'Slash commands: `/help`, `/reset` (clear our conversation), `/whoami`.',
    ].join('\n'),
  };
}

export function buildWhoAmIReply(user: ResolvedAgentUser): AgentReply {
  return {
    text: [
      "Here's what I see about your account:",
      `• Linked HH user id: \`${user.userId}\``,
      `• Organization id: \`${user.organizationId}\``,
      `• Timezone: ${user.timezone}`,
    ].join('\n'),
  };
}

export function buildResetReply(): AgentReply {
  return {
    text: 'Cleared our recent conversation. Starting fresh.',
  };
}

export function buildAttachmentReply(): AgentReply {
  return {
    text: "I can't read attachments yet — please send a text question and I'll help.",
  };
}

export function buildUnlinkedReply(): AgentReply {
  return {
    text:
      "I don't recognise this Chat account yet. Add the bot from your HomeHealth integrations page to connect.",
  };
}
