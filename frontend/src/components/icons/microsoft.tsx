import type { SVGProps } from "react";

export function MicrosoftIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="2em"
      height="2em"
      viewBox="0 0 256 256"
      {...props}
    >
      <path fill="#f1511b" d="M121.666 121.666H0V0h121.666z"></path>
      <path fill="#80cc28" d="M256 121.666H134.335V0H256z"></path>
      <path fill="#00adef" d="M121.663 256.002H0V134.336h121.663z"></path>
      <path fill="#fbbc09" d="M256 256.002H134.335V134.336H256z"></path>
    </svg>
  );
}
