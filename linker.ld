    ENTRY(alignstack)
    SECTIONS
    {
        .text :
        {
            *(.text.alignstack)
            *(.text.sleepytime)
        }
    }
    
