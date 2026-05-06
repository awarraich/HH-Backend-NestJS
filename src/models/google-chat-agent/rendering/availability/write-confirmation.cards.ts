import { CardV2Message, widget } from '../card.types';
import type { CardRenderer } from '../renderer.registry';

const DAY_LABEL = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

const trimTime = (t: string): string => (t.length >= 5 ? t.slice(0, 5) : t);

interface SetAvailabilityRuleOutput {
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

export const setAvailabilityCardRenderer: CardRenderer<SetAvailabilityRuleOutput> =
  {
    toolName: 'setAvailabilityRule',
    render(output, summary) {
      const r = output.rule;
      const day =
        r.dayOfWeek !== null
          ? DAY_LABEL[r.dayOfWeek] ?? `Day ${r.dayOfWeek}`
          : 'Date override';
      const range =
        r.effectiveFrom && r.effectiveUntil
          ? `${r.effectiveFrom} → ${r.effectiveUntil}`
          : r.effectiveUntil
            ? `until ${r.effectiveUntil}`
            : r.effectiveFrom
              ? `from ${r.effectiveFrom}`
              : 'No end date';
      return {
        cardsV2: [
          {
            cardId: 'availability-saved',
            card: {
              header: { title: 'Availability saved' },
              sections: [
                {
                  widgets: [
                    widget.textParagraph(summary || output.message),
                    widget.divider(),
                    widget.decoratedText({
                      topLabel: day,
                      text: `${trimTime(r.startTime)} – ${trimTime(r.endTime)}`,
                      bottomLabel: r.isAvailable ? 'Available' : 'Unavailable',
                    }),
                    widget.decoratedText({
                      topLabel: 'Active range',
                      text: range,
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

interface RequestTimeOffOutput {
  request: {
    id: string;
    startDate: string;
    endDate: string;
    reason: string | null;
    status: 'pending' | 'approved' | 'denied' | 'cancelled';
    reviewNotes: string | null;
    createdAt: string;
  };
  message: string;
}

export const requestTimeOffCardRenderer: CardRenderer<RequestTimeOffOutput> = {
  toolName: 'requestTimeOff',
  render(output, summary) {
    const r = output.request;
    const window =
      r.startDate === r.endDate ? r.startDate : `${r.startDate} → ${r.endDate}`;
    return {
      cardsV2: [
        {
          cardId: 'time-off-submitted',
          card: {
            header: { title: 'Time-off request' },
            sections: [
              {
                widgets: [
                  widget.textParagraph(summary || output.message),
                  widget.divider(),
                  widget.decoratedText({
                    topLabel: window,
                    text: r.reason ?? 'Time off',
                    bottomLabel: `Status: ${r.status}`,
                    wrapText: true,
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

interface CancelTimeOffOutput {
  request: {
    id: string;
    startDate: string;
    endDate: string;
    reason: string | null;
    status: 'pending' | 'approved' | 'denied' | 'cancelled';
    reviewNotes: string | null;
    createdAt: string;
  };
  message: string;
}

export const cancelTimeOffCardRenderer: CardRenderer<CancelTimeOffOutput> = {
  toolName: 'cancelTimeOffRequest',
  render(output, summary): CardV2Message {
    const r = output.request;
    const window =
      r.startDate === r.endDate ? r.startDate : `${r.startDate} → ${r.endDate}`;
    return {
      cardsV2: [
        {
          cardId: 'time-off-cancelled',
          card: {
            header: { title: 'Time-off cancelled' },
            sections: [
              {
                widgets: [
                  widget.textParagraph(summary || output.message),
                  widget.divider(),
                  widget.decoratedText({
                    topLabel: window,
                    text: r.reason ?? 'Time off',
                    bottomLabel: 'Cancelled',
                    wrapText: true,
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
