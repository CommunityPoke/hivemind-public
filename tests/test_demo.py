def test_two_nodes_demo_runs():
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "examples"))
    try:
        import two_nodes_demo

        two_nodes_demo.main()
    finally:
        sys.path.pop(0)
