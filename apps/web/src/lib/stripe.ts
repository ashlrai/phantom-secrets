import Stripe from "stripe";

let _stripe: Stripe | null = null;

export function getStripe(): Stripe {
  if (!_stripe) {
    _stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
      apiVersion: "2026-04-22.dahlia",
    });
  }
  return _stripe;
}

export function getStripePriceId(): string {
  return process.env.STRIPE_PRO_PRICE_ID!;
}

export function getStripeWebhookSecret(): string {
  return process.env.STRIPE_WEBHOOK_SECRET!;
}
