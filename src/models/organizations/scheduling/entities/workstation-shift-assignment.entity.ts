import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  Unique,
} from 'typeorm';
import { LabWorkstation } from './lab-workstation.entity';
import { Shift } from './shift.entity';

@Entity('workstation_shift_assignments')
@Unique('uq_workstation_shift_assignments', ['workstation_id', 'shift_id'])
export class WorkstationShiftAssignment {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  workstation_id: string;

  @Column({ type: 'uuid' })
  shift_id: string;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @ManyToOne(() => LabWorkstation, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'workstation_id' })
  workstation: LabWorkstation;

  @ManyToOne(() => Shift, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'shift_id' })
  shift: Shift;
}
