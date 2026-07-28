import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';
import { Brand } from '@/components/brand';

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: <Brand linked={false} />,
      transparentMode: 'top',
    },
    links: [
      {
        text: 'Capabilities',
        url: '/#capabilities',
      },
      {
        text: 'Safety model',
        url: '/#safety',
      },
      {
        text: 'GitHub',
        url: 'https://github.com/skundu42/opendevops',
        external: true,
      },
    ],
    githubUrl: 'https://github.com/skundu42/opendevops',
  };
}
