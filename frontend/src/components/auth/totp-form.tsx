import { Button, PinInput } from "@mantine/core";
import { useForm, zodResolver } from "@mantine/form";
import { z } from "zod";

const schema = z.object({
  code: z.string(),
});

type FormValues = z.infer<typeof schema>;

interface TotpFormProps {
  onSubmit: (values: FormValues) => void;
  isLoading: boolean;
}

export const TotpForm = (props: TotpFormProps) => {
  const { onSubmit, isLoading } = props;

  const form = useForm({
    mode: "uncontrolled",
    initialValues: {
      code: "",
    },
    validate: zodResolver(schema),
  });

  return (
    <form onSubmit={form.onSubmit(onSubmit)}>
      <PinInput
        length={6}
        type={"number"}
        placeholder=""
        {...form.getInputProps("code")}
      />
      <Button type="submit" mt="xl" loading={isLoading} fullWidth>
        Verify
      </Button>
    </form>
  );
};
