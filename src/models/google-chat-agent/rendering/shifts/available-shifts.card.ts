import {
  CardV2Message,
  CardWidget,
  MAX_INLINE_ROWS,
  widget,
} from '../card.types';
import { formatShiftWindow } from '../format';
import type { CardRenderer } from '../renderer.registry';

interface ListAvailableShiftsOutput {
  shifts: Array<{
    id: string;
    name: string | null;
    shiftType: string | null;
    startAt: string;
    endAt: string;
    recurrenceType: string;
    requiredRoles: string[];
  }>;
  range: { from: string; to: string };
  note: string;
}

export const availableShiftsCardRenderer: CardRenderer<ListAvailableShiftsOutput> =
  {
    toolName: 'listAvailableShifts',
    render(output, summary) {
      const { shifts, range, note } = output;
      const subtitle = `${range.from} → ${range.to}`;

      if (shifts.length === 0) {
        return {
          cardsV2: [
            {
              cardId: 'available-shifts-empty',
              card: {
                header: { title: 'No matching open shifts', subtitle },
                sections: [
                  {
                    widgets: [
                      widget.textParagraph(
                        summary ||
                          "There are no open shifts in this date range that match your role.",
                      ),
                      widget.textParagraph(`_${note}_`),
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
        const bottom = [
          s.shiftType,
          s.recurrenceType,
          s.requiredRoles.length > 0
            ? `Roles: ${s.requiredRoles.join(', ')}`
            : 'Any role',
        ]
          .filter((p): p is string => Boolean(p))
          .join(' · ');
        rows.push(
          widget.decoratedText({
            topLabel: formatShiftWindow(s.startAt, s.endAt),
            text: s.name ?? 'Shift',
            bottomLabel: bottom,
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
            `+ ${overflow} more matching shift${overflow === 1 ? '' : 's'}. Open the web portal to see the full list.`,
          ),
        );
      }

      widgets.push(widget.divider());
      widgets.push(widget.textParagraph(`_${note}_`));

      return {
        cardsV2: [
          {
            cardId: 'available-shifts',
            card: {
              header: {
                title: `Open shifts · ${shifts.length}`,
                subtitle,
              },
              sections: [
                {
                  widgets: summary
                    ? [
                        widget.textParagraph(summary),
                        widget.divider(),
                        ...widgets,
                      ]
                    : widgets,
                },
              ],
            },
          },
        ],
      };
    },
  };
