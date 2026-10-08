import type { ComponentProps } from "react";

// Card composition in the shadcn/ui shape (Card > CardHeader > CardTitle/CardDescription/
// CardAction, CardContent), styled with this app's zinc tokens. Plain elements, no extra
// dependencies; className adds layout only.

const join = (...parts: (string | false | undefined)[]) => parts.filter(Boolean).join(" ");

export function Card({ className, ...props }: ComponentProps<"section">) {
  return (
    <section
      className={join(
        "flex flex-col gap-6 rounded-xl border border-zinc-800 bg-zinc-900/50 py-6 shadow-[inset_0_1px_0_0_rgb(255_255_255/0.04)]",
        className,
      )}
      {...props}
    />
  );
}

export function CardHeader({ className, ...props }: ComponentProps<"div">) {
  return <div className={join("grid auto-rows-min grid-cols-[1fr_auto] items-start gap-1.5 px-6", className)} {...props} />;
}

export function CardTitle({ className, ...props }: ComponentProps<"h2">) {
  return <h2 className={join("font-semibold leading-none text-zinc-50", className)} {...props} />;
}

export function CardDescription({ className, ...props }: ComponentProps<"p">) {
  return <p className={join("col-start-1 text-sm text-zinc-400 text-pretty", className)} {...props} />;
}

export function CardAction({ className, ...props }: ComponentProps<"div">) {
  return <div className={join("col-start-2 row-span-2 row-start-1 self-start justify-self-end", className)} {...props} />;
}

export function CardContent({ className, ...props }: ComponentProps<"div">) {
  return <div className={join("px-6", className)} {...props} />;
}
