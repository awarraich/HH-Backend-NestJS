import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { User } from '../../../../authentication/entities/user.entity';
import { PatientMedicationTimeSlot } from './patient-medication-time-slot.entity';
import { MedicationAdministration } from './medication-administration.entity';

@Entity('patient_medications')
@Index(['patient_id'])
export class PatientMedication {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  patient_id: string;

  @Column({ type: 'varchar', length: 255 })
  name: string;

  @Column({ type: 'varchar', length: 100, nullable: true })
  dosage: string | null;

  @Column({ type: 'varchar', length: 50, nullable: true })
  form: string | null;

  @Column({ type: 'varchar', length: 100, nullable: true })
  frequency: string | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  prescribed_by: string | null;

  @Column({ type: 'text', nullable: true })
  instructions: string | null;

  @Column({ type: 'date', nullable: true })
  start_date: Date | null;

  @Column({ type: 'int', default: 0 })
  on_hand: number;

  @Column({ type: 'int', default: 1 })
  total_quantity: number;

  @Column({ type: 'varchar', length: 50, nullable: true })
  unit: string | null;

  @CreateDateColumn({ type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;

  @Column({ type: 'timestamptz', nullable: true })
  deleted_at: Date | null;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'patient_id' })
  patient: User;

  @OneToMany(() => PatientMedicationTimeSlot, (slot) => slot.patient_medication, {
    cascade: true,
  })
  time_slots: PatientMedicationTimeSlot[];

  @OneToMany(() => MedicationAdministration, (adm) => adm.patient_medication)
  administrations: MedicationAdministration[];
}
