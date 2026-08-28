type BrandMarkProps = {
  className?: string;
};

export function BrandMark({ className }: BrandMarkProps) {
  return (
    <svg
      aria-hidden="true"
      className={className}
      data-brand-mark="witshield"
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path
        d="M12 3.15 18.5 5.7v5.4c0 4.25-2.38 7.42-6.5 9.15-4.12-1.73-6.5-4.9-6.5-9.15V5.7L12 3.15Z"
        stroke="currentColor"
        strokeWidth="1.65"
        strokeLinejoin="round"
      />
      <path
        d="M8.3 12c1.08-1.58 2.32-2.37 3.7-2.37s2.62.79 3.7 2.37c-1.08 1.58-2.32 2.37-3.7 2.37S9.38 13.58 8.3 12Z"
        stroke="currentColor"
        strokeWidth="1.45"
        strokeLinejoin="round"
      />
      <circle cx="12" cy="12" r="1.18" fill="currentColor" />
      <path d="M12 6.25v1.25M12 16.5v1.25" stroke="currentColor" strokeWidth="1.45" strokeLinecap="round" />
    </svg>
  );
}
