import type { MedicationResponse } from '../../../models/patients/medications/medications.service';

export function formatMedicationListToText(list: MedicationResponse[]): string {
  if (!Array.isArray(list) || list.length === 0) {
    return 'No medications found.';
  }
  return list
    .map((m) => {
      const parts = [`- ${m.name}`];
      if (m.dosage) parts.push(` ${m.dosage}`);
      const times = m.timeSlots?.length ? m.timeSlots.join(', ') : 'no times';
      parts.push(` (${times})`);
      const todayStatus = (m.takenForDate ?? [])
        .map((t: { timeSlot: string; taken: boolean }) => `${t.timeSlot}: ${t.taken ? 'taken' : 'not taken'}`)
        .join('; ');
      if (todayStatus) parts.push(` – today: ${todayStatus}`);
      return parts.join('');
    })
    .join('\n');
}
