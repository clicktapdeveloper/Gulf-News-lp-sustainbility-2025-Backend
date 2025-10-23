# Gulf News Email Template Color Implementation Guide

This document provides comprehensive guidelines for implementing the Gulf News color scheme in email templates, ensuring consistency across all backend email communications.

## Color Palette

### Primary Brand Colors

- **Background Color**: `#EBF1E7` (Light sage green)
- **Primary Color**: `#DBE2CD` (Soft sage green)  
- **Secondary Color**: `#224442` (Dark teal green)
- **Tertiary Color**: `#000000` (Black)
- **White Color**: `#FFFFFF` (Pure white)
- **Card Color**: `#E7FB7A` (Light lime green)
- **Border Color**: `#00000040` (Black with 25% opacity)

## Implementation in Email Templates

### 1. Background Colors

```html
<!-- Main email background -->
<body style="background-color: #EBF1E7;">

<!-- Card backgrounds for highlights -->
<div style="background-color: #E7FB7A;">

<!-- Header/navbar backgrounds -->
<div style="background-color: #DBE2CD;">

<!-- White backgrounds for content areas -->
<div style="background-color: #FFFFFF;">
```

### 2. Text Colors

```html
<!-- Primary headings and important text -->
<h1 style="color: #224442;">

<!-- Body text and descriptions -->
<p style="color: #000000;">

<!-- White text on dark backgrounds -->
<span style="color: #FFFFFF;">
```

### 3. Interactive Elements

```html
<!-- Buttons and links -->
<a style="background-color: #224442; color: #FFFFFF;">

<!-- Hover states -->
<a style="color: #224442;">

<!-- Borders -->
<div style="border: 1px solid #00000040;">
```

### 4. Gradient Backgrounds

```html
<!-- Header gradients -->
<div style="background: linear-gradient(135deg, #224442 0%, #DBE2CD 100%);">

<!-- Button gradients -->
<button style="background: linear-gradient(135deg, #224442 0%, #DBE2CD 100%);">
```

## Email Template Structure

### Standard Email Layout

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Email Title</title>
</head>
<body style="margin: 0; padding: 0; font-family: 'Arial', sans-serif; background-color: #EBF1E7;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #EBF1E7; padding: 40px 20px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background-color: #FFFFFF; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
          
          <!-- Header -->
          <tr>
            <td style="background: linear-gradient(135deg, #224442 0%, #DBE2CD 100%); padding: 40px 40px 30px; text-align: center;">
              <h1 style="margin: 0; color: #FFFFFF; font-size: 32px; font-weight: bold;">Email Title</h1>
              <p style="margin: 10px 0 0; color: #FFFFFF; font-size: 16px;">Subtitle</p>
            </td>
          </tr>

          <!-- Content -->
          <tr>
            <td style="padding: 40px;">
              <h2 style="margin: 0 0 20px; color: #224442; font-size: 24px;">Content Heading</h2>
              <p style="margin: 0 0 30px; color: #000000; font-size: 16px; line-height: 1.6;">Content text</p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background-color: #DBE2CD; padding: 30px 40px; text-align: center; border-top: 1px solid #00000040;">
              <p style="margin: 0; color: #000000; font-size: 12px;">© 2024 Gulf News. All rights reserved.</p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
```

## Accessibility Guidelines

### Contrast Ratios

- **#224442 on #EBF1E7**: High contrast (meets WCAG AA standards)
- **#000000 on #EBF1E7**: High contrast (meets WCAG AA standards)  
- **#224442 on #DBE2CD**: Good contrast for interactive elements
- **#FFFFFF on #224442**: High contrast for text on dark backgrounds

### Best Practices

1. **Always test color combinations** for accessibility
2. **Use the secondary color (#224442)** for primary actions and important text
3. **Use the card color (#E7FB7A)** sparingly for highlights and call-to-action elements
4. **Maintain sufficient contrast ratios** for readability
5. **Use white text (#FFFFFF)** only on dark backgrounds

## Email Client Compatibility

### Supported Email Clients

- Gmail (Web, Mobile, Desktop)
- Outlook (2016, 2019, 365, Web)
- Apple Mail (macOS, iOS)
- Yahoo Mail
- Thunderbird
- Mobile email clients

### CSS Support

- Inline styles are used for maximum compatibility
- Gradient backgrounds are supported in most modern email clients
- Border-radius is supported in most clients
- Box-shadow has limited support (used as enhancement only)

## Implementation Checklist

- [ ] Background color set to `#EBF1E7`
- [ ] Header uses gradient `linear-gradient(135deg, #224442 0%, #DBE2CD 100%)`
- [ ] Primary headings use `#224442`
- [ ] Body text uses `#000000`
- [ ] Card backgrounds use `#E7FB7A`
- [ ] Footer background uses `#DBE2CD`
- [ ] Borders use `#00000040`
- [ ] Interactive elements use `#224442` with `#FFFFFF` text
- [ ] All color combinations tested for accessibility
- [ ] Email tested across multiple clients

## File References

- **CSS Variables**: `utils/email-colors.css`
- **Main Implementation**: `index.js` (email template functions)
- **Color Documentation**: This file

## Updates and Maintenance

When updating email templates:

1. Use the color variables defined in `utils/email-colors.css`
2. Test all color combinations for accessibility
3. Verify compatibility across email clients
4. Update this documentation if new colors are added
5. Maintain consistency with frontend color scheme

---

*Last updated: Generated for backend email template integration*
