import { init, g, unwrap } from './init';

/** Bitcoin amount conversions between BTC and satoshis. */
export const amount = {
  /** Convert a BTC value to satoshis.
   *  Calls Go: btcutil.NewAmount() from btcutil. */
  async fromBTC(btc: number): Promise<number> {
    await init();
    return unwrap<number>(g().amount.fromBTC(btc));
  },

  /** Convert satoshis to BTC.
   *  Calls Go: btcutil.Amount.ToBTC() from btcutil. */
  async toBTC(satoshis: number): Promise<number> {
    await init();
    return unwrap<number>(g().amount.toBTC(satoshis));
  },

  /** Format a satoshi amount with a unit label.
   *  Calls Go: btcutil.Amount.Format() from btcutil.
   *  @param unit - "BTC", "mBTC", "uBTC", "satoshi", or "sat". Default: "BTC". */
  async format(satoshis: number, unit?: string): Promise<string> {
    await init();
    return unwrap<string>(g().amount.format(satoshis, unit));
  },
};
