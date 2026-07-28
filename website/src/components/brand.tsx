import Link from 'next/link';
import Image from 'next/image';

export function Brand({
  compact = false,
  linked = true,
}: {
  compact?: boolean;
  linked?: boolean;
}) {
  const content = (
    <>
      <Image
        alt=""
        aria-hidden="true"
        className="brand-logo"
        height={32}
        priority
        src="/opendevops-mark.png"
        width={32}
      />
      {!compact && <span className="brand-word">opendevops</span>}
    </>
  );

  if (!linked) return <span className="brand">{content}</span>;

  return (
    <Link className="brand" href="/" aria-label="opendevops home">
      {content}
    </Link>
  );
}
