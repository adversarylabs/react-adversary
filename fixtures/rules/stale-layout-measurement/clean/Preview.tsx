import { useEffect, useRef, useState } from "react";
export function Preview({markup}: {markup: string}) {
 const box = useRef<HTMLDivElement>(null);
 const [clipped, setClipped] = useState(false);
 useEffect(() => {
  if (box.current) setClipped(box.current.scrollHeight > box.current.clientHeight);
 }, [markup]);
 return <section><div ref={box} dangerouslySetInnerHTML={{__html: markup}} />{clipped && <button>Expand</button>}</section>;
}
