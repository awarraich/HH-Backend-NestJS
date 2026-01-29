import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { CreditPackagesController } from './credit-packages.controller';
import { CreditPackagesService } from './credit-packages.service';
import { CreditPackage } from './entities/credit-package.entity';

@Module({
  imports: [TypeOrmModule.forFeature([CreditPackage])],
  controllers: [CreditPackagesController],
  providers: [CreditPackagesService],
  exports: [CreditPackagesService],
})
export class CreditPackagesModule {}

