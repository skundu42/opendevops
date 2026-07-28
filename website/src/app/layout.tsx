import type { Metadata } from 'next';
import { Barlow_Condensed, IBM_Plex_Mono, Spline_Sans } from 'next/font/google';
import { RootProvider } from 'fumadocs-ui/provider/next';
import './global.css';

const display = Barlow_Condensed({
  subsets: ['latin'],
  variable: '--font-display',
  weight: ['500', '600', '700'],
});

const body = Spline_Sans({
  subsets: ['latin'],
  variable: '--font-body',
  weight: ['400', '500', '600', '700'],
});

const mono = IBM_Plex_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
  weight: ['400', '500', '600'],
});

export const metadata: Metadata = {
  title: {
    default: 'opendevops: Autonomous operations, bounded authority',
    template: '%s · opendevops',
  },
  description:
    'An open-source DevOps agent for infrastructure diagnosis and tightly scoped operations with fail-closed policy, budget stop-losses, and verifiable audit chains.',
  metadataBase: new URL('https://opendevops.dev'),
  openGraph: {
    title: 'opendevops',
    description: 'Autonomous Devops Agent',
    type: 'website',
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html
      className={`${display.variable} ${body.variable} ${mono.variable}`}
      data-scroll-behavior="smooth"
      lang="en"
      suppressHydrationWarning
    >
      <body>
        <RootProvider>{children}</RootProvider>
      </body>
    </html>
  );
}
