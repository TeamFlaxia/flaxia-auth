export const originAllowed = (origin: string | undefined): boolean =>
  origin === 'https://auth.flaxia.app' || origin === 'https://flaxia.app';
