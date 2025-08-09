/**
 * SVG Mock for Jest Testing
 */

import React from 'react';

const SvgMock = React.forwardRef((props, ref) =>
  React.createElement('svg', {
    ...props,
    ref,
    'data-testid': props['data-testid'] || 'svg-mock',
  })
);

SvgMock.displayName = 'SvgMock';

export default SvgMock;
export const ReactComponent = SvgMock;
