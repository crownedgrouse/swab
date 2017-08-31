defmodule Edgar.Mixfile do
  use Mix.Project

  def project do
    [app: :swab,
     version: "1.0.3",
     elixir: "~> 1.2",
     description: description(),
     package: package(),
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     deps: deps()]
  end

  def application do
    [applications: []]
  end

  defp deps() do
    [{:ex_doc, ">= 0.0.0", only: :dev}
    ]
  end

  defp description() do
    "General purpose buffer handling module "
  end

  defp package() do
    [
      # These are the default files included in the package
      files: ["src", "doc", "priv", "mix.exs", "README.md", "LICENSE", "Makefile", "erlang.mk", "rebar.config"],
      maintainers: ["Eric Pailleau"],
      licenses: ["ISC"],
      links: %{"GitHub" => "https://github.com/crownedgrouse/edgar"}
    ]
  end
end
