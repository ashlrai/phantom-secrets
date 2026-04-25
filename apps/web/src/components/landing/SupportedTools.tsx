import { LOGOS } from "./BrandLogos";

export function SupportedTools() {
  return (
    <section className="border-t border-border py-16 sm:py-20">
      <div className="mx-auto max-w-[1100px] px-7">
        <p className="text-center text-[0.78rem] font-medium uppercase tracking-[0.18em] text-t3">
          Built for the tools you already ship with
        </p>

        <div className="mt-10 grid grid-cols-3 gap-x-10 gap-y-8 sm:grid-cols-4 lg:grid-cols-6">
          {LOGOS.map(({ Logo, name }) => (
            <div
              key={name}
              className="group flex flex-col items-center justify-center gap-2"
            >
              <Logo className="h-7 w-7 text-t3 transition-colors duration-200 group-hover:text-t1" />
              <span className="text-[0.72rem] text-t3 transition-colors duration-200 group-hover:text-t2">
                {name}
              </span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
