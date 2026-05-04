import { CardV2Message, CardWidget, widget } from '../card.types';
import type { CardRenderer } from '../renderer.registry';

interface GetMyAvailabilityOutput {
  rules: Array<{
    id: string;
    dayOfWeek: number | null;
    date: string | null;
    startTime: string;
    endTime: string;
    isAvailable: boolean;
    shiftType: string | null;
    effectiveFrom: string | null;
    effectiveUntil: string | null;
  }>;
  workPreferences: {
    maxHoursPerWeek: number;
    preferredShiftType: string;
    availableForOvertime: boolean;
    availableForOnCall: boolean;
    workType: string;
  };
}

const DAY_LABEL = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

const trimTime = (t: string): string =>
  // "09:00:00" → "09:00"; leave "09:00" alone.
  t.length >= 5 ? t.slice(0, 5) : t;

export const myAvailabilityCardRenderer: CardRenderer<GetMyAvailabilityOutput> =
  {
    toolName: 'getMyAvailability',
    render(output, summary) {
      const weekly = output.rules
        .filter((r) => r.dayOfWeek !== null && !r.date)
        .sort((a, b) => (a.dayOfWeek ?? 0) - (b.dayOfWeek ?? 0));
      const overrides = output.rules.filter((r) => r.date);

      const weeklyWidgets: CardWidget[] =
        weekly.length === 0
          ? [
              widget.textParagraph(
                "_No recurring weekly availability set. Tell me something like 'I'm available Tuesdays 9 to 5' to add one._",
              ),
            ]
          : weekly.flatMap((r, idx) => {
              const rows: CardWidget[] = [];
              const verb = r.isAvailable ? 'Available' : 'Unavailable';
              rows.push(
                widget.decoratedText({
                  topLabel: DAY_LABEL[r.dayOfWeek ?? 0] ?? `day ${r.dayOfWeek}`,
                  text: `${trimTime(r.startTime)} – ${trimTime(r.endTime)}`,
                  bottomLabel: r.shiftType
                    ? `${verb} · ${r.shiftType}`
                    : verb,
                  wrapText: true,
                }),
              );
              if (idx < weekly.length - 1) rows.push(widget.divider());
              return rows;
            });

      const overrideWidgets: CardWidget[] = overrides.flatMap((r, idx) => {
        const rows: CardWidget[] = [];
        const verb = r.isAvailable ? 'Available' : 'Unavailable';
        rows.push(
          widget.decoratedText({
            topLabel: r.date ?? '',
            text: `${trimTime(r.startTime)} – ${trimTime(r.endTime)}`,
            bottomLabel: verb,
            wrapText: true,
          }),
        );
        if (idx < overrides.length - 1) rows.push(widget.divider());
        return rows;
      });

      const prefs = output.workPreferences;
      const prefsWidgets: CardWidget[] = [
        widget.decoratedText({
          topLabel: 'Max hours / week',
          text: String(prefs.maxHoursPerWeek),
        }),
        widget.decoratedText({
          topLabel: 'Preferred shift',
          text: prefs.preferredShiftType,
        }),
        widget.decoratedText({
          topLabel: 'Overtime / on-call',
          text: `${prefs.availableForOvertime ? 'OT yes' : 'OT no'} · ${prefs.availableForOnCall ? 'On-call yes' : 'On-call no'}`,
        }),
        widget.decoratedText({
          topLabel: 'Work type',
          text: prefs.workType,
        }),
      ];

      const sections = [
        ...(summary ? [{ widgets: [widget.textParagraph(summary)] }] : []),
        { header: 'Weekly availability', widgets: weeklyWidgets },
      ];
      if (overrideWidgets.length > 0) {
        sections.push({
          header: 'Date-specific overrides',
          widgets: overrideWidgets,
        });
      }
      sections.push({ header: 'Work preferences', widgets: prefsWidgets });

      return {
        cardsV2: [
          {
            cardId: 'my-availability',
            card: {
              header: { title: 'Your availability' },
              sections,
            },
          },
        ],
      };
    },
  };
