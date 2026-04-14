import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  Unique,
} from 'typeorm';
import { Shift } from './shift.entity';
import { ProviderRole } from '../../../employees/entities/provider-role.entity';

@Entity('shift_roles')
@Unique('uq_shift_roles', ['shift_id', 'provider_role_id'])
export class ShiftRole {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  shift_id: string;

  @Column({ type: 'uuid' })
  provider_role_id: string;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @ManyToOne(() => Shift, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'shift_id' })
  shift: Shift;

  @ManyToOne(() => ProviderRole, { onDelete: 'CASCADE', eager: true })
  @JoinColumn({ name: 'provider_role_id' })
  providerRole: ProviderRole;
}
