import { CardV2Message, widget } from './card.types';

/**
 * Card returned when the agent is disabled (global kill switch off, or the
 * org's M13 flag is off). Short, polite, no LLM call needed. Invoked
 * directly by the M8 webhook MESSAGE branch.
 */
export function buildDisabledCard(opts: { reason?: string } = {}): CardV2Message {
  const message =
    opts.reason ??
    "The scheduling assistant isn't enabled for your account yet. Reach out to your administrator if you'd like access.";
  return {
    cardsV2: [
      {
        cardId: 'agent-disabled',
        card: {
          header: { title: 'Scheduling assistant unavailable' },
          sections: [
            {
              widgets: [widget.textParagraph(message)],
            },
          ],
        },
      },
    ],
  };
}
