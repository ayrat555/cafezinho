defmodule CafezinhoTest do
  use ExUnit.Case
  doctest Cafezinho

  test "greets the world" do
    assert Cafezinho.hello() == :world
  end
end
