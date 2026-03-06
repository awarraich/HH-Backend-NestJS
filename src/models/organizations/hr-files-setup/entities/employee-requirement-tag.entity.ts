import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  Index,
  Unique,
} from 'typeorm';
import { Employee } from '../../../employees/entities/employee.entity';
import { RequirementTag } from './requirement-tag.entity';

@Entity('employee_requirement_tags')
@Unique(['employee_id', 'requirement_tag_id'])
@Index(['employee_id'])
@Index(['requirement_tag_id'])
export class EmployeeRequirementTag {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  employee_id: string;

  @Column({ type: 'uuid' })
  requirement_tag_id: string;

  @CreateDateColumn({ type: 'timestamp with time zone', default: () => 'NOW()' })
  created_at: Date;

  @ManyToOne(() => Employee, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'employee_id' })
  employee: Employee;

  @ManyToOne(() => RequirementTag, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'requirement_tag_id' })
  requirementTag: RequirementTag;
}
