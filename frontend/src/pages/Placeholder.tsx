interface PlaceholderProps {
  title: string;
  description: string;
}

/** Honest placeholder: names the future capability without faking it. */
export function Placeholder({ title, description }: PlaceholderProps) {
  return (
    <section className="card" aria-label={title}>
      <h3>{title}</h3>
      <p>{description}</p>
      <p>
        <span className="badge neutral">Planned — not implemented in Step 1</span>
      </p>
    </section>
  );
}
