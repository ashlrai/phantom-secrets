import { Composition } from "remotion";
import { PhantomDemo } from "./PhantomDemo";

export const RemotionRoot = () => {
  return (
    <Composition
      id="PhantomDemo"
      component={PhantomDemo}
      durationInFrames={1350}
      fps={30}
      width={1920}
      height={1080}
    />
  );
};
