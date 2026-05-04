import {
  CardV2Message,
  CardWidget,
  MAX_INLINE_ROWS,
  widget,
} from '../card.types';
import { formatShiftWindow, locationLabel } from '../format';
import type { CardRenderer } from '../renderer.registry';

/**
 * Output shape of the listMyShifts tool — duplicated as a structural
 * type rather than imported, so the renderer doesn't reach into the
 * tool-internal Zod schema infer.
 */
interface ListMyShiftsOutput {
  shifts: Array<{
    id: string;
    shiftId: string;
    shiftName: string | null;
    scheduledDate: string;
    startAt: string;
    endAt: string;
    status: string;
    role: string | null;
    location: {
      department: string | null;
      station: string | null;
      room: string | null;
      bed: string | null;
      chair: string | null;
    };
    notes: string | null;
  }>;
  range: { from: string; to: string };
}

export const myShiftsCardRenderer: CardRenderer<ListMyShiftsOutput> = {
  toolName: 'listMyShifts',
  render(output, summary) {
    const { shifts, range } = output;
    const subtitle = `${range.from} → ${range.to}`;

    if (shifts.length === 0) {
      return {
        cardsV2: [
          {
            cardId: 'my-shifts-empty',
            card: {
              header: { title: 'No shifts scheduled', subtitle },
              sections: [
                {
                  widgets: [
                    widget.textParagraph(
                      summary || "You don't have any shifts in this date range.",
                    ),
                  ],
                },
              ],
            },
          },
        ],
      };
    }

    const visible = shifts.slice(0, MAX_INLINE_ROWS);
    const overflow = shifts.length - visible.length;

    const widgets: CardWidget[] = visible.flatMap((s, idx) => {
      const rows: CardWidget[] = [];
      const loc = locationLabel(s.location);
      const bottomLabel = [
        s.role,
        loc,
        s.status !== 'SCHEDULED' ? s.status : null,
      ]
        .filter((p): p is string => Boolean(p))
        .join(' · ');
      rows.push(
        widget.decoratedText({
          topLabel: s.scheduledDate,
          text: s.shiftName ?? 'Shift',
          bottomLabel: [formatShiftWindow(s.startAt, s.endAt), bottomLabel]
            .filter(Boolean)
            .join('\n'),
          wrapText: true,
        }),
      );
      if (idx < visible.length - 1) rows.push(widget.divider());
      return rows;
    });

    if (overflow > 0) {
      widgets.push(widget.divider());
      widgets.push(
        widget.textParagraph(
          `+ ${overflow} more shift${overflow === 1 ? '' : 's'}. Open the web portal to see the full list.`,
        ),
      );
    }

    return {
      cardsV2: [
        {
          cardId: 'my-shifts',
          card: {
            header: {
              title: `Your shifts · ${shifts.length}`,
              subtitle,
            },
            sections: [
              {
                widgets: summary
                  ? [widget.textParagraph(summary), widget.divider(), ...widgets]
                  : widgets,
              },
            ],
          },
        },
      ],
    };
  },
};
