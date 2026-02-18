import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { PatientMedication } from './patient-medication.entity';

@Entity('medication_administrations')
@Index(['patient_medication_id', 'scheduled_date'])
export class MedicationAdministration {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  patient_medication_id: string;

  @Column({ type: 'date' })
  scheduled_date: Date;

  @Column({ type: 'varchar', length: 20, nullable: true })
  time_slot: string | null;

  @Column({ type: 'boolean', default: false })
  taken: boolean;

  @Column({ type: 'timestamptz', nullable: true })
  taken_at: Date | null;

  @Column({ type: 'varchar', length: 20, nullable: true })
  method: string | null;

  @Column({ type: 'uuid', nullable: true })
  recorded_by_user_id: string | null;

  @ManyToOne(() => PatientMedication, (med) => med.administrations, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'patient_medication_id' })
  patient_medication: PatientMedication;
}
