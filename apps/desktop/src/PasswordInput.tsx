import { forwardRef, useId, useState, type InputHTMLAttributes } from "react";
import { Icon } from "./Icon";
import { t } from "./i18n";

/** One password control across authentication, recovery and device approval. */
export const PasswordInput = forwardRef<
  HTMLInputElement,
  Omit<InputHTMLAttributes<HTMLInputElement>, "type">
>(function PasswordInput(props, ref) {
  const [visible, setVisible] = useState(false);
  const generatedId = useId();
  const id = props.id ?? generatedId;
  return (
    <span className="password-field">
      <input
        autoCapitalize="none"
        autoCorrect="off"
        spellCheck={false}
        {...props}
        id={id}
        ref={ref}
        type={visible ? "text" : "password"}
      />
      <button
        type="button"
        className="password-reveal"
        aria-label={t(visible ? "password.hide" : "password.show")}
        aria-controls={id}
        aria-pressed={visible}
        disabled={props.disabled}
        onPointerDown={(event) => event.preventDefault()}
        onClick={() => setVisible((value) => !value)}
      >
        <Icon name={visible ? "eyeOff" : "eye"} />
      </button>
    </span>
  );
});
