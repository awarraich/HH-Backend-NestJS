import { CreditPackage } from '../entities/credit-package.entity';

export class CreditPackageSerializer {
  serialize(creditPackage: CreditPackage): any {
    return {
      id: creditPackage.id,
      name: creditPackage.name,
      credits: creditPackage.credits,
      price_usd: Number(creditPackage.price_usd),
      stripe_price_id: creditPackage.stripe_price_id,
      is_active: creditPackage.is_active,
      created_at: creditPackage.created_at,
      updated_at: creditPackage.updated_at,
    };
  }

  serializeMany(creditPackages: CreditPackage[]): any[] {
    return creditPackages.map((package_) => this.serialize(package_));
  }
}

