import {
  CardV2Message,
  CardWidget,
  MAX_INLINE_ROWS,
  widget,
} from '../card.types';
import type { CardRenderer } from '../renderer.registry';

interface GetMyTimeOffRequestsOutput {
  requests: Array<{
    id: string;
    startDate: string;
    endDate: string;
    reason: string | null;
    status: 'pending' | 'approved' | 'denied' | 'cancelled';
    reviewNotes: string | null;
    createdAt: string;
  }>;
  range: { from: string; to: string };
}

const STATUS_LABEL: Record<
  GetMyTimeOffRequestsOutput['requests'][number]['status'],
  string
> = {
  pending: 'Pending',
  approved: 'Approved',
  denied: 'Denied',
  cancelled: 'Cancelled',
};

export const timeOffListCardRenderer: CardRenderer<GetMyTimeOffRequestsOutput> =
  {
    toolName: 'getMyTimeOffRequests',
    render(output, summary) {
      const subtitle = `${output.range.from} → ${output.range.to}`;

      if (output.requests.length === 0) {
        return {
          cardsV2: [
            {
              cardId: 'time-off-empty',
              card: {
                header: { title: 'No time-off requests', subtitle },
                sections: [
                  {
                    widgets: [
                      widget.textParagraph(
                        summary || 'No time-off requests in this date range.',
                      ),
                    ],
                  },
                ],
              },
            },
          ],
        };
      }

      const visible = output.requests.slice(0, MAX_INLINE_ROWS);
      const overflow = output.requests.length - visible.length;

      const widgets: CardWidget[] = visible.flatMap((r, idx) => {
        const rows: CardWidget[] = [];
        const window =
          r.startDate === r.endDate
            ? r.startDate
            : `${r.startDate} → ${r.endDate}`;
        const bottom = [STATUS_LABEL[r.status], r.reason]
          .filter((p): p is string => Boolean(p))
          .join(' · ');
        rows.push(
          widget.decoratedText({
            topLabel: window,
            text: r.reason ?? 'Time off',
            bottomLabel: bottom,
            wrapText: true,
          }),
        );
        if (r.reviewNotes) {
          rows.push(
            widget.decoratedText({
              topLabel: 'Review notes',
              text: r.reviewNotes,
              wrapText: true,
            }),
          );
        }
        if (idx < visible.length - 1) rows.push(widget.divider());
        return rows;
      });

      if (overflow > 0) {
        widgets.push(widget.divider());
        widgets.push(
          widget.textParagraph(
            `+ ${overflow} more request${overflow === 1 ? '' : 's'}. Open the web portal to see the full list.`,
          ),
        );
      }

      return {
        cardsV2: [
          {
            cardId: 'time-off-list',
            card: {
              header: {
                title: `Time-off requests · ${output.requests.length}`,
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
