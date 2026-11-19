import logoUrl from "../assets/seesec-logo.svg";

/**
 * The product lockup: Seesec's mark, the product name, and on the large
 * variant the vendor line.
 *
 * One component because this used to be four copies of the same two spans --
 * in `Layout`, `LoginPage`, `ChangePasswordPage` and `EnrollPage` -- which is
 * three places to forget when the logo changes.
 *
 * The mark is an `<img>` pointing at a single asset, so replacing the brand is
 * replacing one file. It is `alt=""` and `aria-hidden` because the product
 * name sits immediately beside it as real text; captioning the image too
 * would make a screen reader announce the name twice.
 *
 * The product is UbuntuGuard and the vendor is Seesec. Both are shown rather
 * than one standing in for the other: an employee on the enrollment page needs
 * to recognise who is asking to manage their laptop, and "UbuntuGuard" alone
 * does not tell them that.
 */
export default function Brand({
  size = "normal",
  showVendor,
}: {
  size?: "normal" | "large";
  /** Defaults to on for the large lockup, off for the compact one. */
  showVendor?: boolean;
}) {
  const large = size === "large";
  const vendor = showVendor ?? large;

  return (
    <div className={large ? "brand large" : "brand"}>
      <img className="brand-mark" src={logoUrl} alt="" aria-hidden="true" />
      <span className="brand-text">
        <span className="brand-name">UbuntuGuard</span>
        {vendor ? <span className="brand-vendor">by Seesec</span> : null}
      </span>
    </div>
  );
}
