import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  OneToOne,
  JoinColumn,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';
import { Employee } from './employee.entity';

@Entity('employee_profiles')
@Index(['employee_id'], { unique: true })
export class EmployeeProfile {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid', unique: true })
  employee_id: string;

  @Column({ type: 'varchar', length: 255 })
  name: string;

  @Column({ type: 'varchar', length: 100, nullable: true })
  profile_image: string | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  address_line_1: string | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  address_line_2: string | null;

  @Column({ type: 'varchar', length: 100, nullable: true })
  city: string | null;

  @Column({ type: 'varchar', length: 100, nullable: true })
  state: string | null;

  @Column({ type: 'varchar', length: 20, nullable: true })
  phone_number: string | null;

  @Column({ type: 'varchar', length: 20, nullable: true })
  gender: string | null;

  @Column({ type: 'integer', nullable: true })
  age: number | null;

  @Column({ type: 'date', nullable: true })
  date_of_birth: Date | null;

  @Column({ type: 'jsonb', nullable: true })
  emergency_contact: Record<string, unknown> | null;

  @Column({ type: 'varchar', length: 100, nullable: true })
  specialization: string | null;

  @Column({ type: 'integer', nullable: true })
  years_of_experience: number | null;

  @Column({ type: 'varchar', length: 100, nullable: true })
  certification: string | null;

  @Column({ type: 'jsonb', nullable: true })
  board_certifications: Record<string, unknown> | null;

  // Onboarding-completion timestamps. All four start as null and are set
  // when the employee finishes (or skips) the first-login wizard. They
  // double as a compliance audit trail — HR can pull "who has acknowledged
  // HIPAA" / "who hasn't completed I-9" reports straight off these columns.
  @Column({ type: 'timestamptz', nullable: true })
  portal_wizard_completed_at: Date | null;

  @Column({ type: 'timestamptz', nullable: true })
  hipaa_acknowledged_at: Date | null;

  @Column({ type: 'timestamptz', nullable: true })
  background_check_acknowledged_at: Date | null;

  @Column({ type: 'timestamptz', nullable: true })
  i9_acknowledged_at: Date | null;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;

  @OneToOne(() => Employee, (employee) => employee.profile, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'employee_id' })
  employee: Employee;
}
