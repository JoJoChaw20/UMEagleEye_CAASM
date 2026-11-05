// The EagleEye logo. `tone` picks the lockup for the ground it sits on:
//   'auto'   – follows the theme (dark-ink lockup in light mode, silver in dark mode)
//   'onDark' – always the silver-wordmark lockup (the navy rail)
// `variant="mark"` is the emblem alone, which reads on both grounds.
export default function BrandLogo({ variant = 'lockup', tone = 'auto', className = '', alt = 'UMEagleEye' }) {
  if (variant === 'mark') {
    return <img src="/brand/eagleeye-mark.webp" alt={alt} width="256" height="256" className={className} draggable="false" />
  }
  if (tone === 'onDark') {
    return <img src="/brand/eagleeye-lockup-dark.webp" alt={alt} width="720" height="309" className={className} draggable="false" />
  }
  return (
    <>
      <img src="/brand/eagleeye-lockup-dark.webp" alt={alt} width="720" height="309" className={`logo-auto logo-on-dark ${className}`} draggable="false" />
      <img src="/brand/eagleeye-lockup-light.webp" alt={alt} width="720" height="309" className={`logo-auto logo-on-light ${className}`} draggable="false" />
    </>
  )
}
