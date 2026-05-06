import { CardV2Message, widget } from '../card.types';
import type { CardRenderer } from '../renderer.registry';

interface SetAvailabilityForDateOutput {
  rule: {
    id: string;
    dayOfWeek: number | null;
    date: string | null;
    startTime: string;
    endTime: string;
    isAvailable: boolean;
    shiftType: string | null;
    effectiveFrom: string | null;
    effectiveUntil: string | null;
  };
  message: string;
}

const trimTime = (t: string): string => (t.length >= 5 ? t.slice(0, 5) : t);

export const availabilityForDateCardRenderer: CardRenderer<SetAvailabilityForDateOutput> =
  {
    toolName: 'setAvailabilityForDate',
    render(output, summary): CardV2Message {
      const r = output.rule;
      return {
        cardsV2: [
          {
            cardId: 'availability-for-date-saved',
            card: {
              header: { title: 'Availability saved (one-time)' },
              sections: [
                {
                  widgets: [
                    widget.textParagraph(summary || output.message),
                    widget.divider(),
                    widget.decoratedText({
                      topLabel: r.date ?? 'Date override',
                      text: `${trimTime(r.startTime)} – ${trimTime(r.endTime)}`,
                      bottomLabel: r.isAvailable ? 'Available' : 'Unavailable',
                    }),
                  ],
                },
              ],
            },
          },
        ],
      };
    },
  };
