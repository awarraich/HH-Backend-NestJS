import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { PatientMedication } from './patient-medication.entity';

@Entity('patient_medication_time_slots')
@Index(['patient_medication_id'])
export class PatientMedicationTimeSlot {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  patient_medication_id: string;

  @Column({ type: 'varchar', length: 20, nullable: true })
  time_of_day: string | null;

  @Column({ type: 'smallint', default: 0 })
  sort_order: number;

  @ManyToOne(() => PatientMedication, (med) => med.time_slots, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'patient_medication_id' })
  patient_medication: PatientMedication;
}
