import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { UserSerializer } from './serializers/user.serializer';
import { StringHelper } from '../../common/helpers/string.helper';
import { UserInterface } from './interfaces/user.interface';

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);
  private readonly userSerializer = new UserSerializer();

  constructor(
    @InjectRepository(User)
    private readonly usersRepository: Repository<User>,
  ) {}

  async findAll(): Promise<UserInterface[]> {
    const users = await this.usersRepository.find();
    return this.userSerializer.serializeMany(users) as UserInterface[];
  }

  async findOne(id: string): Promise<UserInterface> {
    const user = await this.usersRepository.findOne({ where: { id } });
    if (!user) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }
    return this.userSerializer.serialize(user) as UserInterface;
  }

  /**
   * Finds a user by their email address
   *
   * @param email - The email address of the user to find
   * @returns Promise resolving to the serialized user interface
   * @throws NotFoundException if user with the email is not found
   *
   * @example
   * const user = await usersService.findByEmail('user@example.com');
   */
  async findByEmail(email: string): Promise<UserInterface> {
    // HIPAA Compliance: Mask email in logs for audit trail
    const maskedEmail = StringHelper.maskEmail(email);
    this.logger.log(`Attempting to find user by email: ${maskedEmail}`);

    const user = await this.usersRepository.findOne({ where: { email } });

    if (!user) {
      this.logger.warn(`User not found for email: ${maskedEmail}`);
      throw new NotFoundException(`User with email ${email} not found`);
    }

    this.logger.log(`User found successfully for email: ${maskedEmail}`);
    return this.userSerializer.serialize(user) as UserInterface;
  }
}
