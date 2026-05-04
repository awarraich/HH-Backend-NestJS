import { CardV2Message, widget } from './card.types';

/**
 * Error card surfaced to the user when something goes wrong inside the
 * agent loop. Includes an `errorId` (the turnId or a generated correlation
 * id) so support can grep logs to find the actual stack.
 *
 * Not registered with CardRendererRegistry — invoked directly by the agent
 * service in the catch block of the turn handler.
 */
export function buildErrorCard(opts: {
  errorId: string;
  message?: string;
}): CardV2Message {
  return {
    cardsV2: [
      {
        cardId: 'agent-error',
        card: {
          header: { title: 'Something went wrong' },
          sections: [
            {
              widgets: [
                widget.textParagraph(
                  opts.message ??
                    "I hit an error while handling that. Please try again — if it keeps happening, share this code with support.",
                ),
                widget.decoratedText({
                  topLabel: 'Error code',
                  text: opts.errorId,
                }),
              ],
            },
          ],
        },
      },
    ],
  };
}
