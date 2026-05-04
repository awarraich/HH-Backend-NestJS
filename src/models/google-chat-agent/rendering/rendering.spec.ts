import { CardRendererRegistry } from './renderer.registry';
import { MAX_CARD_BYTES, MAX_INLINE_ROWS } from './card.types';
import { myShiftsCardRenderer } from './shifts/my-shifts.card';
import { shiftDetailCardRenderer } from './shifts/shift-detail.card';
import { availableShiftsCardRenderer } from './shifts/available-shifts.card';
import { buildErrorCard } from './error.card';
import { buildDisabledCard } from './disabled.card';

const myShifts = (count: number) => ({
  shifts: Array.from({ length: count }, (_, i) => ({
    id: `es-${i}`,
    shiftId: `shift-${i}`,
    shiftName: `Shift ${i}`,
    scheduledDate: '2026-05-10',
    startAt: '2026-05-10T08:00:00Z',
    endAt: '2026-05-10T16:00:00Z',
    status: 'SCHEDULED',
    role: 'NURSE',
    location: {
      department: 'Cardiology',
      station: 'A',
      room: '101',
      bed: null,
      chair: null,
    },
    notes: null,
  })),
  range: { from: '2026-05-10', to: '2026-05-17' },
});

const availableShifts = (count: number) => ({
  shifts: Array.from({ length: count }, (_, i) => ({
    id: `shift-${i}`,
    name: `Open shift ${i}`,
    shiftType: 'DAY',
    startAt: '2026-05-10T08:00:00Z',
    endAt: '2026-05-10T16:00:00Z',
    recurrenceType: 'ONE_TIME',
    requiredRoles: ['NURSE'],
  })),
  range: { from: '2026-05-10', to: '2026-05-17' },
  note: 'Talk to your manager about being assigned.',
});

const sizeOf = (payload: unknown): number =>
  Buffer.byteLength(JSON.stringify(payload), 'utf8');

describe('myShiftsCardRenderer (M9)', () => {
  // M9-U1: Empty list renders the "nothing scheduled" variant.
  it('renders an empty-state card when there are no shifts', () => {
    const card = myShiftsCardRenderer.render(myShifts(0), '');
    expect(card).not.toBeNull();
    expect(card!.cardsV2[0].cardId).toBe('my-shifts-empty');
    expect(card!.cardsV2[0].card.header?.title).toMatch(/No shifts/i);
  });

  it('renders one section with one widget per shift below MAX_INLINE_ROWS', () => {
    const card = myShiftsCardRenderer.render(myShifts(3), 'Here are your shifts');
    const section = card!.cardsV2[0].card.sections[0];
    // summary paragraph + divider + 3 shifts × (decoratedText + divider) - 1 trailing divider
    // Just assert there's one decoratedText per shift.
    const decoratedCount = section.widgets.filter((w) =>
      Object.prototype.hasOwnProperty.call(w, 'decoratedText'),
    ).length;
    expect(decoratedCount).toBe(3);
  });

  // M9-U2: Lists exceeding MAX_INLINE_ROWS render with a "view all in app" hint.
  it('caps inline rows at MAX_INLINE_ROWS and adds an overflow hint', () => {
    const total = MAX_INLINE_ROWS + 7;
    const card = myShiftsCardRenderer.render(myShifts(total), '');
    const widgets = card!.cardsV2[0].card.sections[0].widgets;
    const decoratedCount = widgets.filter((w) =>
      Object.prototype.hasOwnProperty.call(w, 'decoratedText'),
    ).length;
    expect(decoratedCount).toBe(MAX_INLINE_ROWS);

    const paragraphs = widgets.filter(
      (w): w is { textParagraph: { text: string } } =>
        Object.prototype.hasOwnProperty.call(w, 'textParagraph'),
    );
    const overflowText = paragraphs.find((p) => /more shift/i.test(p.textParagraph.text));
    expect(overflowText).toBeDefined();
    expect(overflowText!.textParagraph.text).toContain('7 more');
  });

  // M9-U3: Card payload size stays under Google's limit on a 50-item stress fixture.
  it('produces a payload comfortably under MAX_CARD_BYTES on a 50-shift fixture', () => {
    const card = myShiftsCardRenderer.render(myShifts(50), 'Here is your roster');
    expect(sizeOf(card)).toBeLessThan(MAX_CARD_BYTES);
  });

  it('uses scheduledDate as the topLabel of each shift row', () => {
    const card = myShiftsCardRenderer.render(myShifts(2), '');
    const section = card!.cardsV2[0].card.sections[0];
    const decoratedTexts = section.widgets.filter(
      (w): w is { decoratedText: { topLabel?: string } } =>
        Object.prototype.hasOwnProperty.call(w, 'decoratedText'),
    );
    expect(decoratedTexts[0].decoratedText.topLabel).toBe('2026-05-10');
  });

  it('threads the model summary into the card header section when provided', () => {
    const card = myShiftsCardRenderer.render(myShifts(2), 'Here are your two shifts');
    const widgets = card!.cardsV2[0].card.sections[0].widgets;
    const firstParagraph = widgets.find((w) =>
      Object.prototype.hasOwnProperty.call(w, 'textParagraph'),
    ) as { textParagraph: { text: string } } | undefined;
    expect(firstParagraph?.textParagraph.text).toBe('Here are your two shifts');
  });
});

describe('shiftDetailCardRenderer (M9)', () => {
  it('renders a not-found card when found=false', () => {
    const card = shiftDetailCardRenderer.render(
      { found: false, message: "You're not assigned to that shift." },
      '',
    );
    expect(card!.cardsV2[0].cardId).toBe('shift-detail-not-found');
    expect(card!.cardsV2[0].card.header?.title).toMatch(/not found/i);
  });

  it('renders shift + assignments sections when found=true', () => {
    const card = shiftDetailCardRenderer.render(
      {
        found: true,
        shift: {
          id: 'shift-1',
          name: 'NOC',
          shiftType: 'NIGHT',
          startAt: '2026-05-10T18:00:00Z',
          endAt: '2026-05-11T02:00:00Z',
          recurrenceType: 'WEEKDAYS',
          requiredRoles: ['NURSE'],
        },
        myAssignments: [
          {
            id: 'es-1',
            shiftId: 'shift-1',
            shiftName: 'NOC',
            scheduledDate: '2026-05-12',
            startAt: '2026-05-10T18:00:00Z',
            endAt: '2026-05-11T02:00:00Z',
            status: 'SCHEDULED',
            role: 'NURSE',
            location: {
              department: null,
              station: null,
              room: null,
              bed: null,
              chair: null,
            },
            notes: null,
          },
        ],
      },
      '',
    );
    const sections = card!.cardsV2[0].card.sections;
    const headers = sections.map((s) => s.header).filter(Boolean);
    expect(headers).toContain('Shift');
    expect(headers).toEqual(expect.arrayContaining([expect.stringMatching(/Your assignments/)]));
  });
});

describe('availableShiftsCardRenderer (M9)', () => {
  it('renders an empty-state with the manager note', () => {
    const card = availableShiftsCardRenderer.render(availableShifts(0), '');
    expect(card!.cardsV2[0].cardId).toBe('available-shifts-empty');
    const widgets = card!.cardsV2[0].card.sections[0].widgets;
    const noteParagraph = widgets.find(
      (w): w is { textParagraph: { text: string } } =>
        Object.prototype.hasOwnProperty.call(w, 'textParagraph') &&
        /manager/i.test((w as { textParagraph: { text: string } }).textParagraph.text),
    );
    expect(noteParagraph).toBeDefined();
  });

  it('caps at MAX_INLINE_ROWS and includes manager note + overflow text', () => {
    const total = MAX_INLINE_ROWS + 3;
    const card = availableShiftsCardRenderer.render(availableShifts(total), '');
    const widgets = card!.cardsV2[0].card.sections[0].widgets;
    const decoratedCount = widgets.filter((w) =>
      Object.prototype.hasOwnProperty.call(w, 'decoratedText'),
    ).length;
    expect(decoratedCount).toBe(MAX_INLINE_ROWS);

    const paragraphs = widgets.filter(
      (w): w is { textParagraph: { text: string } } =>
        Object.prototype.hasOwnProperty.call(w, 'textParagraph'),
    );
    expect(paragraphs.some((p) => /more matching/i.test(p.textParagraph.text))).toBe(true);
    expect(paragraphs.some((p) => /manager/i.test(p.textParagraph.text))).toBe(true);
  });

  it('payload stays under MAX_CARD_BYTES on a 50-shift stress fixture', () => {
    const card = availableShiftsCardRenderer.render(availableShifts(50), '');
    expect(sizeOf(card)).toBeLessThan(MAX_CARD_BYTES);
  });
});

describe('error and disabled cards (M9)', () => {
  // M9-U4: Tool errors render an error card with errorId for log correlation.
  it('error card includes the errorId verbatim', () => {
    const card = buildErrorCard({ errorId: 'turn-abc-123' });
    const widgets = card.cardsV2[0].card.sections[0].widgets;
    const decoratedTexts = widgets.filter(
      (w): w is { decoratedText: { topLabel?: string; text: string } } =>
        Object.prototype.hasOwnProperty.call(w, 'decoratedText'),
    );
    const errorIdRow = decoratedTexts.find(
      (w) => w.decoratedText.topLabel === 'Error code',
    );
    expect(errorIdRow?.decoratedText.text).toBe('turn-abc-123');
  });

  it('error card uses caller-supplied message when provided', () => {
    const card = buildErrorCard({ errorId: 'x', message: 'Custom error message' });
    const widgets = card.cardsV2[0].card.sections[0].widgets;
    const paragraphs = widgets.filter(
      (w): w is { textParagraph: { text: string } } =>
        Object.prototype.hasOwnProperty.call(w, 'textParagraph'),
    );
    expect(paragraphs[0].textParagraph.text).toBe('Custom error message');
  });

  it('disabled card has the canonical title', () => {
    const card = buildDisabledCard();
    expect(card.cardsV2[0].card.header?.title).toMatch(/unavailable/i);
  });

  it('disabled card honors a caller-supplied reason', () => {
    const card = buildDisabledCard({ reason: 'Only enabled for the night shift.' });
    const widgets = card.cardsV2[0].card.sections[0].widgets;
    const paragraphs = widgets.filter(
      (w): w is { textParagraph: { text: string } } =>
        Object.prototype.hasOwnProperty.call(w, 'textParagraph'),
    );
    expect(paragraphs[0].textParagraph.text).toBe('Only enabled for the night shift.');
  });
});

describe('CardRendererRegistry (M9)', () => {
  it('rejects duplicate registrations for the same tool', () => {
    const reg = new CardRendererRegistry();
    reg.register(myShiftsCardRenderer);
    expect(() => reg.register(myShiftsCardRenderer)).toThrow(/already registered/i);
  });

  it('returns null when no renderer is registered for a tool', () => {
    const reg = new CardRendererRegistry();
    expect(reg.render('unregistered-tool', {}, '')).toBeNull();
  });

  it('delegates to the registered renderer', () => {
    const reg = new CardRendererRegistry();
    reg.register(myShiftsCardRenderer);
    const card = reg.render('listMyShifts', myShifts(1), 'hi');
    expect(card?.cardsV2[0].card.header?.title).toMatch(/Your shifts/);
  });

  it('size and list reflect registrations', () => {
    const reg = new CardRendererRegistry();
    expect(reg.size()).toBe(0);
    reg.register(myShiftsCardRenderer);
    reg.register(shiftDetailCardRenderer);
    reg.register(availableShiftsCardRenderer);
    expect(reg.size()).toBe(3);
    expect(reg.list().sort()).toEqual([
      'getShiftDetails',
      'listAvailableShifts',
      'listMyShifts',
    ]);
  });

  it('all three M5 renderers map to the M5 tool names exactly', () => {
    expect(myShiftsCardRenderer.toolName).toBe('listMyShifts');
    expect(shiftDetailCardRenderer.toolName).toBe('getShiftDetails');
    expect(availableShiftsCardRenderer.toolName).toBe('listAvailableShifts');
  });
});
