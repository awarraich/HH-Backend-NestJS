import {
  CardV2Message,
  CardWidget,
  widget,
} from '../card.types';
import { formatShiftWindow, locationLabel } from '../format';
import type { CardRenderer } from '../renderer.registry';

interface GetShiftDetailsOutput {
  found: boolean;
  message?: string;
  shift?: {
    id: string;
    name: string | null;
    shiftType: string | null;
    startAt: string;
    endAt: string;
    recurrenceType: string;
    requiredRoles: string[];
  };
  myAssignments?: Array<{
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
}

export const shiftDetailCardRenderer: CardRenderer<GetShiftDetailsOutput> = {
  toolName: 'getShiftDetails',
  render(output, summary) {
    if (!output.found) {
      return {
        cardsV2: [
          {
            cardId: 'shift-detail-not-found',
            card: {
              header: { title: 'Shift not found' },
              sections: [
                {
                  widgets: [
                    widget.textParagraph(
                      summary ||
                        output.message ||
                        "You're not assigned to that shift, or it doesn't exist in your organization.",
                    ),
                  ],
                },
              ],
            },
          },
        ],
      };
    }

    const shift = output.shift!;
    const assignments = output.myAssignments ?? [];

    const aboutWidgets: CardWidget[] = [
      widget.decoratedText({
        topLabel: 'Shift',
        text: shift.name ?? 'Untitled shift',
        bottomLabel: [shift.shiftType, shift.recurrenceType]
          .filter((p): p is string => Boolean(p))
          .join(' · '),
        wrapText: true,
      }),
    ];
    if (shift.requiredRoles.length > 0) {
      aboutWidgets.push(
        widget.decoratedText({
          topLabel: 'Required role(s)',
          text: shift.requiredRoles.join(', '),
        }),
      );
    }

    const assignmentWidgets: CardWidget[] = assignments.flatMap((a, idx) => {
      const rows: CardWidget[] = [];
      const loc = locationLabel(a.location);
      const bottom = [
        a.role,
        loc,
        a.status !== 'SCHEDULED' ? a.status : null,
        a.notes,
      ]
        .filter((p): p is string => Boolean(p))
        .join(' · ');
      rows.push(
        widget.decoratedText({
          topLabel: a.scheduledDate,
          text: formatShiftWindow(a.startAt, a.endAt),
          bottomLabel: bottom || undefined,
          wrapText: true,
        }),
      );
      if (idx < assignments.length - 1) rows.push(widget.divider());
      return rows;
    });

    return {
      cardsV2: [
        {
          cardId: 'shift-detail',
          card: {
            header: {
              title: shift.name ?? 'Shift details',
            },
            sections: [
              ...(summary ? [{ widgets: [widget.textParagraph(summary)] }] : []),
              { header: 'Shift', widgets: aboutWidgets },
              {
                header: `Your assignments · ${assignments.length}`,
                widgets:
                  assignmentWidgets.length > 0
                    ? assignmentWidgets
                    : [
                        widget.textParagraph(
                          'No date-specific assignments to display.',
                        ),
                      ],
              },
            ],
          },
        },
      ],
    };
  },
};
