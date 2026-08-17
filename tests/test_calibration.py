import calibration


def test_selects_weakest_strength_meeting_target():
    null = [float(i) for i in range(100)]
    result = calibration.select_strength(
        {
            1.0: [50.0] * 100,
            2.0: [100.0] * 90 + [0.0] * 10,
            4.0: [101.0] * 100,
        },
        null,
        target_tpr=0.9,
    )
    assert result["chosen"] == 2.0
